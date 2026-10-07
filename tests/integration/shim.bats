#!/usr/bin/env bats
# The bootstrap shim (bin/tacctl.sh; docs/plans/go-rewrite.md 5.2): its own rows of the offline and
# partial-failure matrix, which the Go tests of internal/lifecycle cannot
# reach because they are bash. A copy of the shim runs from a scratch tree
# with TACCTL_TEST_ROOT, so /usr/local/bin/tacctl and /usr/local/go are
# under the test's directory; git, wget and the Go toolchain are stand-ins.
# The release-binary tests (WP6.8) serve release assets from a directory
# (TACCTL_RELEASE_BASE_URL, copied by the wget stand-in), signed at test
# time by the real ssh-keygen with an ed25519 key generated for this file
# (setup_file; no key is kept in the repository);
# the one that installs a release binary installs a copy of dist/tacctl.

load ../helpers/setup
load ../helpers/mocks

bats_require_minimum_version 1.5.0

SHIM="${TACCTL_SRC}/bin/tacctl.sh"
HEAD_COMMIT="2222222222222222222222222222222222222222"
OLD_COMMIT="1111111111111111111111111111111111111111"

# An ephemeral release key for this file: TEST_KEY (private, 0600) and
# TEST_SIGNERS, its allowed_signers line for the identity tacctl-release.
setup_file() {
    export TEST_KEY="${BATS_FILE_TMPDIR}/test-signing-key"
    export TEST_SIGNERS="${BATS_FILE_TMPDIR}/allowed_signers"
    ssh-keygen -q -t ed25519 -N '' -C tacctl-release-test -f "$TEST_KEY"
    printf 'tacctl-release namespaces="tacctl-release" %s\n' "$(cut -d' ' -f1,2 "${TEST_KEY}.pub")" > "$TEST_SIGNERS"
}

setup() {
    tacctl_mocks_init
    export TACCTL_TEST_ROOT="${BATS_TEST_TMPDIR}/root"
    export TACCTL_SKIP_SUDO=1
    export GOCACHE="${BATS_TEST_TMPDIR}/gocache"
    export TMPDIR="${BATS_TEST_TMPDIR}/tmp"
    mkdir -p "$TMPDIR"
    T="${BATS_TEST_TMPDIR}/tree"
    B="${TACCTL_TEST_ROOT}/usr/local/bin/tacctl"
    GOROOT_DIR="${TACCTL_TEST_ROOT}/usr/local/go"
    mkdir -p "${T}/bin" "${T}/cmd/tacctl" "$(dirname "$B")"
    cp "$SHIM" "${T}/bin/tacctl.sh"
    chmod 755 "${T}/bin/tacctl.sh"
    printf 'module github.com/rett/tacctl\n\ngo 1.26.0\n' > "${T}/go.mod"
    # git: the tree is at HEAD_COMMIT, reached by a switch from 'develop'.
    stub_cmd git '
case "$*" in
  *"rev-parse --abbrev-ref @{-1}"*) echo develop ;;
  *"rev-parse HEAD"*) echo "'"$HEAD_COMMIT"'" ;;
  *--exact-match*) echo "fatal: no tag exactly matches" >&2; exit 128 ;;
  *describe*) echo 0.2.0-test ;;
  *"log -1"*) echo 2026-10-03T00:00:00Z ;;
esac'
}

# binary <commit> <tag>: an installed command built from <commit> that
# prints '<tag> <args>'.
binary() {
    cat > "$B" <<EOF
#!/usr/bin/env bash
if [[ "\$1 \${2:-}" == "version --long" ]]; then echo "tacctl x"; echo "commit:     $1"; exit 0; fi
echo "$2 \$*"
EOF
    chmod 755 "$B"
}

# go_toolchain <dir> <version> [fail]: a Go stand-in whose 'build -o <f>'
# writes an installed command built from HEAD_COMMIT ('NEW'), or fails.
go_toolchain() {
    local dir="$1" version="$2" fail="${3:-}"
    mkdir -p "${dir}/bin"
    cat > "${dir}/bin/go" <<EOF
#!/usr/bin/env bash
echo "go \$*" >> "${CALLS_LOG}"
[[ "\$1" != build ]] || echo "goenv GOOS=\${GOOS:-} GOARCH=\${GOARCH:-}" >> "${CALLS_LOG}"
if [[ "\$1" == version ]]; then echo "go version go${version} linux/amd64"; exit 0; fi
[[ -z "${fail}" ]] || { echo "go: ${fail}" >&2; exit 1; }
out=""
while [[ \$# -gt 0 ]]; do [[ "\$1" == -o ]] && out="\$2"; shift; done
cat > "\$out" <<'BIN'
#!/usr/bin/env bash
if [[ "\$1 \${2:-}" == "version --long" ]]; then echo "tacctl x"; echo "commit:     ${HEAD_COMMIT}"; exit 0; fi
echo "NEW \$*"
BIN
EOF
    chmod 755 "${dir}/bin/go"
}

# go_tarball <version> [sum]: wget serves go<version>.linux-amd64.tar.gz
# (a Go stand-in) and its .sha256 (the real sum, or the one given; "none":
# no checksum published; "offline": nothing at all).
go_tarball() {
    local version="$1" sum="${2:-}" staging="${BATS_TEST_TMPDIR}/staging"
    go_toolchain "${staging}/go" "$version"
    tar -C "$staging" -czf "${BATS_TEST_TMPDIR}/go.tgz" go
    [[ -n "$sum" ]] || sum=$(sha256sum "${BATS_TEST_TMPDIR}/go.tgz" | cut -d' ' -f1)
    stub_cmd wget '
[[ "'"$sum"'" != offline ]] || exit 4
case "$*" in
  *.sha256*) [[ "'"$sum"'" == none ]] && exit 8; echo "'"$sum"'" ;;
  *) cp "'"${BATS_TEST_TMPDIR}/go.tgz"'" "${@: -2:1}" ;;
esac'
}

run_shim() { run "${T}/bin/tacctl.sh" "$@"; }

# refute_called <regex>: no stub call matches (a bare '! stub_called' would
# not fail a test: errexit ignores '!').
refute_called() {
    if stub_called "$1"; then
        echo "unexpected call matching '$1':" >&2
        stub_calls >&2
        return 1
    fi
}

@test "shim: a current binary runs with the arguments; nothing is built" {
    binary "$HEAD_COMMIT" OLD
    run_shim user list --x
    assert_success
    assert_output "OLD user list --x"
    refute_called '^go '
    refute_called '^wget '
}

@test "shim: a binary built from another commit is rebuilt, installed and run" {
    binary "$OLD_COMMIT" OLD
    go_toolchain "$GOROOT_DIR" 1.26.2
    run_shim status
    assert_success
    assert_line "NEW status"
    assert_output --partial "Building ${B} from ${T}..."
    [[ -f "$B" && ! -L "$B" && "$(stat -c %a "$B")" == 755 && ! -e "${B}.new" ]]
    stub_called "^go build -trimpath -buildvcs=false -ldflags -s -w -X main.version=0.2.0-test -X main.commit=${HEAD_COMMIT} .* -o ${B}.new ./cmd/tacctl$"
    # Current now: the next run builds nothing.
    : > "$CALLS_LOG"
    run_shim status
    assert_output "NEW status"
    refute_called '^go build'
}

@test "shim: the 0.1.16 symlink (or no command at all) is replaced by the binary" {
    go_toolchain "$GOROOT_DIR" 1.26.2
    ln -s "${T}/bin/tacctl.sh" "$B"
    run_shim upgrade
    assert_success
    assert_line "NEW upgrade"
    [[ -f "$B" && ! -L "$B" ]]
    rm -f "$B"
    run_shim version
    assert_line "NEW version"
}

@test "shim: without Go, Go 1.26.2 is downloaded, checked and installed, then the binary built" {
    binary "$OLD_COMMIT" OLD
    go_tarball 1.26.2
    run_shim user list
    assert_success
    assert_output --partial "Installing Go 1.26.2..."
    assert_output --partial "Go tarball checksum verified."
    assert_output --partial "Go 1.26.2 installed."
    assert_line "NEW user list"
    stub_called '^wget -q --no-hsts -O .*/go1\.26\.2\.linux-amd64\.tar\.gz https://dl\.google\.com/go/go1\.26\.2\.linux-amd64\.tar\.gz$'
    stub_called '^wget -q --no-hsts -O- https://dl\.google\.com/go/go1\.26\.2\.linux-amd64\.tar\.gz\.sha256$'
    [[ -x "${GOROOT_DIR}/bin/go" ]]
    # The download went to a private directory that is gone.
    [[ -z "$(ls -A "$TMPDIR")" ]]
}

@test "shim: an older Go is upgraded; a newer one is used as it is, never replaced" {
    go_toolchain "$GOROOT_DIR" 1.25.4
    go_tarball 1.26.2
    run_shim status
    assert_success
    assert_output --partial "Go 1.25.4 found, upgrading to 1.26.2..."
    assert_line "NEW status"
    run "${GOROOT_DIR}/bin/go" version
    assert_output "go version go1.26.2 linux/amd64"

    rm -rf "$GOROOT_DIR" "$B"
    : > "$CALLS_LOG"
    go_toolchain "$GOROOT_DIR" 1.27.1
    run_shim status
    assert_success
    assert_line "NEW status"
    refute_called '^wget '
    run "${GOROOT_DIR}/bin/go" version
    assert_output "go version go1.27.1 linux/amd64"
}

@test "shim: a Go tarball whose checksum does not match is not installed; Decision 20's way back" {
    binary "$OLD_COMMIT" OLD
    go_toolchain "$GOROOT_DIR" 1.25.4
    go_tarball 1.26.2 0000000000000000000000000000000000000000000000000000000000000000
    run_shim status
    assert_failure 1
    assert_output --partial "Go tarball checksum mismatch!"
    assert_output --partial "tacctl could not be built (see above). The installed command is unchanged."
    # The older Go is still there, the installed command untouched.
    run "${GOROOT_DIR}/bin/go" version
    assert_output "go version go1.25.4 linux/amd64"
    run "$B" status
    assert_output "OLD status"
    [[ -z "$(ls -A "$TMPDIR")" ]]
}

# refused_unverified: Go was not installed for want of a checksum; the Go
# in place (1.25.4) and the installed command are as they were, the
# download is gone, and Decision 20's way back follows.
refused_unverified() {
    assert_failure 1
    [[ "$stderr" == *$'\e[0;31m[ERROR]\e[0m Go 1.26.2 was not installed: it could not be verified (no checksum at https://dl.google.com/go/go1.26.2.linux-amd64.tar.gz.sha256).'* ]] \
        || { echo "$stderr"; return 1; }
    [[ "$stderr" == *"tacctl could not be built (see above). The installed command is unchanged."* ]]
    [[ "$stderr" != *"checksum verified"* && "$stderr" != *"Go 1.26.2 installed."* ]]
    run "${GOROOT_DIR}/bin/go" version
    assert_output "go version go1.25.4 linux/amd64"
    run "$B" status
    assert_output "OLD status"
    [[ -z "$(ls -A "$TMPDIR")" ]]
}

@test "shim: no checksum to be had: Go is not installed (refused unverified), exit 1" {
    binary "$OLD_COMMIT" OLD
    go_toolchain "$GOROOT_DIR" 1.25.4
    go_tarball 1.26.2 none
    run --separate-stderr "${T}/bin/tacctl.sh" status
    refused_unverified
}

@test "shim: a web page (or anything but 64 lowercase hex digits) where the checksum should be is no checksum: refused" {
    binary "$OLD_COMMIT" OLD
    go_toolchain "$GOROOT_DIR" 1.25.4
    go_tarball 1.26.2
    local real answer
    real=$(sha256sum "${BATS_TEST_TMPDIR}/go.tgz" | cut -d' ' -f1)
    for answer in '<!DOCTYPE html>' "${real^^}" "${real}  go1.26.2.linux-amd64.tar.gz" "${real:1}" ''; do
        printf '%s\n' "$answer" > "${BATS_TEST_TMPDIR}/sha-answer"
        stub_cmd wget '
case "$*" in
  *.sha256*) cat "'"${BATS_TEST_TMPDIR}/sha-answer"'" ;;
  *) cp "'"${BATS_TEST_TMPDIR}/go.tgz"'" "${@: -2:1}" ;;
esac'
        run --separate-stderr "${T}/bin/tacctl.sh" status
        refused_unverified
    done
}

@test "shim: a checksum with blanks or a CRLF around it is trimmed and verified" {
    binary "$OLD_COMMIT" OLD
    go_tarball 1.26.2
    local real
    real=$(sha256sum "${BATS_TEST_TMPDIR}/go.tgz" | cut -d' ' -f1)
    printf '  %s \r\n\n' "$real" > "${BATS_TEST_TMPDIR}/sha-answer"
    stub_cmd wget '
case "$*" in
  *.sha256*) cat "'"${BATS_TEST_TMPDIR}/sha-answer"'" ;;
  *) cp "'"${BATS_TEST_TMPDIR}/go.tgz"'" "${@: -2:1}" ;;
esac'
    run_shim status
    assert_success
    assert_output --partial "Go tarball checksum verified."
    assert_line "NEW status"
}

@test "shim: offline with no Go: it fails loudly on every run and leaves the installed command as it was" {
    ln -s "${T}/bin/tacctl.sh" "$B"
    go_tarball 1.26.2 offline
    local i
    for i in 1 2; do
        run --separate-stderr "${T}/bin/tacctl.sh" status
        assert_failure 1
        assert_output ""
        [[ "$stderr" == *"Could not download https://dl.google.com/go/go1.26.2.linux-amd64.tar.gz."* ]]
        [[ "$stderr" == *"[ERROR]"*" sudo git -C ${T} checkout 0.1.18 && sudo tacctl config branch develop"* ]]
        [[ -L "$B" && "$(readlink "$B")" == "${T}/bin/tacctl.sh" ]]
    done
    [[ ! -e "$GOROOT_DIR" ]]
}

@test "shim: a build that fails prints Decision 20's text exactly and exits 1; the installed command is unchanged" {
    binary "$OLD_COMMIT" OLD
    go_toolchain "$GOROOT_DIR" 1.26.2 "updates to go.mod needed"
    run --separate-stderr "${T}/bin/tacctl.sh" status
    assert_failure 1
    local want
    want=$(printf '%s\n' \
        "go: updates to go.mod needed" \
        $'\e[0;31m[ERROR]\e[0m tacctl could not be built (see above). The installed command is unchanged.' \
        $'\e[0;31m[ERROR]\e[0m Fix the cause and run the command again, or go back to the bash release:' \
        $'\e[0;31m[ERROR]\e[0m   sudo git -C '"${T}"' checkout 0.1.18 && sudo tacctl config branch develop')
    [[ "$stderr" == *"$want" ]] || { echo "$stderr"; return 1; }
    run "$B" status
    assert_output "OLD status"
    [[ ! -e "${B}.new" ]]
}

@test "shim: with no previous branch the way back names master" {
    go_toolchain "$GOROOT_DIR" 1.26.2 "boom"
    stub_cmd git '
case "$*" in
  *"rev-parse --abbrev-ref @{-1}"*) echo "fatal: no previous branch" >&2; exit 128 ;;
  *"rev-parse HEAD"*) echo "'"$HEAD_COMMIT"'" ;;
esac'
    run_shim status
    assert_failure 1
    assert_output --partial "checkout 0.1.18 && sudo tacctl config branch master"
}

@test "shim: not root and not current: it re-runs itself under sudo ('host' keeps the agent socket)" {
    unset TACCTL_SKIP_SUDO
    stub_cmd sudo
    binary "$OLD_COMMIT" OLD
    run_shim user list
    assert_success
    stub_called "^sudo ${T}/bin/tacctl.sh user list$"
    SSH_AUTH_SOCK=/run/agent.sock run_shim host list
    stub_called "^sudo SSH_AUTH_SOCK=/run/agent.sock ${T}/bin/tacctl.sh host list$"
    # A current binary needs no root here: it runs it (and it re-execs
    # itself as it needs).
    binary "$HEAD_COMMIT" OLD
    : > "$CALLS_LOG"
    run_shim user list
    assert_output "OLD user list"
    refute_called '^sudo '
}

@test "shim: --build builds only (no root, nothing installed), with the recipe's usage" {
    go_toolchain "$GOROOT_DIR" 1.26.2
    run_shim --build
    assert_failure 1
    assert_output "Usage: tacctl.sh --build <out> [--tags <tags>] [--goarch <arch>]"
    run_shim --build "${BATS_TEST_TMPDIR}/out/tacctl" --goarch
    assert_failure 1
    assert_output "Usage: tacctl.sh --build <out> [--tags <tags>] [--goarch <arch>]"
    run_shim --build "${BATS_TEST_TMPDIR}/out/tacctl" --tags testknobs
    assert_success
    [[ -x "${BATS_TEST_TMPDIR}/out/tacctl" && ! -e "$B" ]]
    stub_called '^go build -trimpath -buildvcs=false -tags testknobs '
    # The host's architecture unless --goarch names one (a cross-build for
    # linux/<arch>, 'make release-assets').
    stub_called '^goenv GOOS= GOARCH=$'
    : > "$CALLS_LOG"
    run_shim --build "${BATS_TEST_TMPDIR}/out/tacctl-arm64" --goarch arm64
    assert_success
    stub_called '^goenv GOOS=linux GOARCH=arm64$'
    refute_called ' -tags '
}

@test "shim: one build recipe: --build, the install path, 'make build' and the Go upgrade use it" {
    # Defined once, called by '--build' and by the obtain path (the
    # bootstrap and '--install-binary').
    [[ "$(grep -c '^tacctl_go_build() {$' "$SHIM")" -eq 1 ]]
    [[ "$(grep -cE '^[[:space:]]*tacctl_go_build ' "$SHIM")" -eq 2 ]]
    [[ "$(grep -cE '^[[:space:]]*shim_obtain ' "$SHIM")" -eq 2 ]]
    # 'make build' is '--build' with the test knobs; 'make release-assets'
    # is '--build' with --goarch and without them.
    grep -qE '^[[:space:]]+bin/tacctl\.sh --build dist/tacctl --tags testknobs$' "${TACCTL_SRC}/Makefile"
    grep -qE '^[[:space:]]+bin/tacctl\.sh --build .*--goarch ' "${TACCTL_SRC}/Makefile"
    run grep -E 'tacctl\.sh --build .*--goarch .*testknobs' "${TACCTL_SRC}/Makefile"
    assert_failure 1
    # The Go upgrade and install obtain the command with
    # '<deploy>/bin/tacctl.sh --install-binary <command>' ('--build' for a
    # tree whose shim predates it).
    grep -qE 'filepath\.Join\([^)]*"bin", "tacctl\.sh"\)' "${TACCTL_SRC}/internal/lifecycle/build.go"
    grep -q '"--install-binary"' "${TACCTL_SRC}/internal/lifecycle/build.go"
    grep -q '"--build"' "${TACCTL_SRC}/internal/lifecycle/build.go"
}

# --- release binaries (WP6.8) --------------------------------------------------

REL_TAG="0.2.1"
DIST="${TACCTL_SRC}/dist/tacctl"

# release_tree [tag] [commit]: git puts the tree at <tag> exactly, on
# <commit> (default HEAD_COMMIT); release/allowed_signers is TEST_SIGNERS.
release_tree() {
    local tag="${1:-$REL_TAG}" commit="${2:-$HEAD_COMMIT}"
    stub_cmd git '
case "$*" in
  *"rev-parse --abbrev-ref @{-1}"*) echo develop ;;
  *"rev-parse HEAD"*) echo "'"$commit"'" ;;
  *describe*) echo "'"$tag"'" ;;
  *"log -1"*) echo 2026-10-03T00:00:00Z ;;
esac'
    mkdir -p "${T}/release"
    cp "$TEST_SIGNERS" "${T}/release/allowed_signers"
}

# fake_release_binary <file> <commit>: a stand-in release binary built from
# <commit> that prints 'REL <args>'.
fake_release_binary() {
    cat > "$1" <<EOF
#!/usr/bin/env bash
if [[ "\$1 \${2:-}" == "version --long" ]]; then echo "tacctl ${REL_TAG}"; echo "commit:     $2"; exit 0; fi
echo "REL \$*"
EOF
    chmod 755 "$1"
}

# release_assets <arch> <binary> [key]: the release of REL_TAG under
# TACCTL_RELEASE_BASE_URL: <binary> as tacctl-<tag>-linux-<arch>, its
# SHA256SUMS, and SHA256SUMS.sig made by ssh-keygen -Y sign with <key>
# (default TEST_KEY); RELDIR is that directory.
release_assets() {
    local arch="$1" bin="$2" key="${3:-}" asset="tacctl-${REL_TAG}-linux-${1}"
    export TACCTL_RELEASE_BASE_URL="${BATS_TEST_TMPDIR}/releases"
    RELDIR="${TACCTL_RELEASE_BASE_URL}/${REL_TAG}"
    mkdir -p "$RELDIR"
    cp "$bin" "${RELDIR}/${asset}"
    (cd "$RELDIR" && sha256sum "$asset" > SHA256SUMS)
    [[ -n "$key" ]] || key="$TEST_KEY"
    rm -f "${RELDIR}/SHA256SUMS.sig"
    ssh-keygen -q -Y sign -f "$key" -n tacctl-release "${RELDIR}/SHA256SUMS" 2> /dev/null
    [[ -s "${RELDIR}/SHA256SUMS.sig" ]]
}

# release_wget: wget copies release files from TACCTL_RELEASE_BASE_URL
# (exit 8 for a missing one), and serves the Go stand-in tarball and its
# checksum.
release_wget() {
    stub_cmd wget '
out=""; url="${*: -1}"
while [[ $# -gt 0 ]]; do [[ "$1" == -O ]] && out="$2"; shift; done
case "$url" in
  '"${BATS_TEST_TMPDIR}"'/releases/*) [[ -f "$url" ]] || exit 8; cp "$url" "$out" ;;
  *.sha256) sha256sum "'"${BATS_TEST_TMPDIR}"'/go.tgz" | cut -d" " -f1 ;;
  *) cp "'"${BATS_TEST_TMPDIR}"'/go.tgz" "$out" ;;
esac'
}

# not_used <reason>: the one INFO line, then the build from source.
not_used() {
    assert_success
    assert_output --partial "Release binary for ${REL_TAG} not used (${1}); building from source."
    assert_output --partial "Building ${B} from ${T}..."
    assert_line "NEW status"
    refute_output --partial "release binary (linux/"
    stub_called '^go build '
    [[ -z "$(ls -A "$TMPDIR")" ]]
}

@test "shim: at a release tag the signed release binary is downloaded, verified and installed; nothing is built" {
    local commit
    commit=$(TACCTL_SKIP_SUDO=1 "$DIST" version --long | sed -n 's/^commit:[[:space:]]*//p')
    [[ "$commit" =~ ^[0-9a-f]{40}$ ]]
    release_tree "$REL_TAG" "$commit"
    go_toolchain "$GOROOT_DIR" 1.26.2
    binary "$OLD_COMMIT" OLD
    release_assets amd64 "$DIST"
    release_wget
    run_shim version
    assert_success
    assert_output --partial "Installing the ${REL_TAG} release binary (linux/amd64, verified)"
    assert_line --regexp '^tacctl [0-9]'
    refute_output --partial "Building "
    refute_output --partial "not used"
    cmp "$B" "$DIST"
    [[ "$(stat -c %a "$B")" == 755 && ! -e "${B}.new" ]]
    for f in SHA256SUMS SHA256SUMS.sig "tacctl-${REL_TAG}-linux-amd64"; do
        stub_called "^wget -q --no-hsts --timeout=30 --tries=2 -O .*/${f} ${TACCTL_RELEASE_BASE_URL}/${REL_TAG}/${f}\$"
    done
    refute_called '^go build'
    [[ -z "$(ls -A "$TMPDIR")" ]]
    # Current now: the next run downloads nothing.
    : > "$CALLS_LOG"
    run_shim version
    assert_success
    refute_called '^wget '
}

@test "shim: a release whose SHA256SUMS is signed by another key is not used; built from source" {
    release_tree
    go_toolchain "$GOROOT_DIR" 1.26.2
    fake_release_binary "${BATS_TEST_TMPDIR}/rel" "$HEAD_COMMIT"
    ssh-keygen -q -t ed25519 -N '' -C other -f "${BATS_TEST_TMPDIR}/other-key"
    release_assets amd64 "${BATS_TEST_TMPDIR}/rel" "${BATS_TEST_TMPDIR}/other-key"
    release_wget
    run_shim status
    not_used "the signature of SHA256SUMS does not verify"
}

@test "shim: a release binary that does not match SHA256SUMS is not used; built from source" {
    release_tree
    go_toolchain "$GOROOT_DIR" 1.26.2
    fake_release_binary "${BATS_TEST_TMPDIR}/rel" "$HEAD_COMMIT"
    release_assets amd64 "${BATS_TEST_TMPDIR}/rel"
    # Replaced after signing: the signature still verifies, the sum does not.
    echo "# tampered" >> "${RELDIR}/tacctl-${REL_TAG}-linux-amd64"
    release_wget
    run_shim status
    not_used "tacctl-${REL_TAG}-linux-amd64 does not match SHA256SUMS"
    [[ "$(cat "$B")" != *tampered* ]]
}

@test "shim: a signed release binary built from another commit is not used; built from source" {
    release_tree
    go_toolchain "$GOROOT_DIR" 1.26.2
    fake_release_binary "${BATS_TEST_TMPDIR}/rel" "$OLD_COMMIT"
    release_assets amd64 "${BATS_TEST_TMPDIR}/rel"
    release_wget
    run_shim status
    not_used "it was built from commit ${OLD_COMMIT}, not ${HEAD_COMMIT}"
}

@test "shim: without ssh-keygen the release binary is not used (nothing downloaded); built from source" {
    release_tree
    go_toolchain "$GOROOT_DIR" 1.26.2
    fake_release_binary "${BATS_TEST_TMPDIR}/rel" "$HEAD_COMMIT"
    release_assets amd64 "${BATS_TEST_TMPDIR}/rel"
    release_wget
    # A PATH with everything of /usr/bin but ssh-keygen.
    local sys="${BATS_TEST_TMPDIR}/sysbin"
    mkdir -p "$sys"
    ln -s /usr/bin/* "$sys"/
    rm -f "${sys}/ssh-keygen"
    PATH="${STUB_BIN}:${sys}" run "${T}/bin/tacctl.sh" status
    not_used "ssh-keygen is not installed"
    refute_called '^wget '
}

@test "shim: with no key in release/allowed_signers the release binary is not used (nothing downloaded); built from source" {
    release_tree
    # An allowed_signers file with comments only, as a tree with no key has.
    printf '# The public half of the tacctl release key\n#   tacctl-release namespaces="tacctl-release" ssh-ed25519 AAAA...\n' \
        > "${T}/release/allowed_signers"
    go_toolchain "$GOROOT_DIR" 1.26.2
    fake_release_binary "${BATS_TEST_TMPDIR}/rel" "$HEAD_COMMIT"
    release_assets amd64 "${BATS_TEST_TMPDIR}/rel"
    release_wget
    run_shim status
    not_used "no release key configured"
    refute_called '^wget '
    # No file at all is the same.
    rm -f "${T}/release/allowed_signers" "$B"
    run_shim status
    not_used "no release key configured"
}

@test "shim: on a branch no release download is attempted, and nothing is said about one" {
    # The setup's git: 'describe --exact-match' finds no tag.
    mkdir -p "${T}/release"
    cp "$TEST_SIGNERS" "${T}/release/allowed_signers"
    go_toolchain "$GOROOT_DIR" 1.26.2
    fake_release_binary "${BATS_TEST_TMPDIR}/rel" "$HEAD_COMMIT"
    release_assets amd64 "${BATS_TEST_TMPDIR}/rel"
    release_wget
    run_shim status
    assert_success
    assert_line "NEW status"
    assert_output --partial "Building ${B} from ${T}..."
    refute_output --partial "Release binary"
    refute_called '^wget '
    stub_called '^git -C .* describe --tags --exact-match '
}

@test "shim: on arm64 (aarch64) the Go tarball and the release asset are the arm64 ones" {
    local commit
    commit=$(TACCTL_SKIP_SUDO=1 "$DIST" version --long | sed -n 's/^commit:[[:space:]]*//p')
    release_tree "$REL_TAG" "$commit"
    stub_cmd uname '[[ "$1" == -m ]] && echo aarch64'
    # No Go: the stand-in tarball is downloaded under its arm64 name.
    go_tarball 1.26.2
    release_assets arm64 "$DIST"
    release_wget
    run_shim version
    assert_success
    assert_output --partial "Go 1.26.2 installed."
    assert_output --partial "Installing the ${REL_TAG} release binary (linux/arm64, verified)"
    stub_called '^wget -q --no-hsts -O .*/go1\.26\.2\.linux-arm64\.tar\.gz https://dl\.google\.com/go/go1\.26\.2\.linux-arm64\.tar\.gz$'
    stub_called "/${REL_TAG}/tacctl-${REL_TAG}-linux-arm64\$"
    refute_called 'amd64'
    cmp "$B" "$DIST"
    # Any other machine: no Go download (the failure names it); with a Go
    # in place, no release binary ('no release binary for linux/<m>').
    rm -rf "$GOROOT_DIR" "$B"
    stub_cmd uname '[[ "$1" == -m ]] && echo riscv64'
    run_shim status
    assert_failure 1
    assert_output --partial "no Go download for riscv64 (amd64 and arm64 only)"
    go_toolchain "$GOROOT_DIR" 1.26.2
    run_shim status
    assert_success
    assert_output --partial "Release binary for ${REL_TAG} not used (no release binary for linux/riscv64); building from source."
    assert_line "NEW status"
}

@test "shim: --install-binary obtains into <out> only (no sudo, no toolchain step, nothing run); a failure is exit 1" {
    unset TACCTL_SKIP_SUDO
    stub_cmd sudo
    run_shim --install-binary
    assert_failure 1
    assert_output "Usage: tacctl.sh --install-binary <out>"
    # The release binary, its INFO line on stdout.
    release_tree
    go_toolchain "$GOROOT_DIR" 1.26.2
    fake_release_binary "${BATS_TEST_TMPDIR}/rel" "$HEAD_COMMIT"
    release_assets amd64 "${BATS_TEST_TMPDIR}/rel"
    release_wget
    local out="${BATS_TEST_TMPDIR}/out/tacctl"
    run --separate-stderr "${T}/bin/tacctl.sh" --install-binary "$out"
    assert_success
    assert_output "$(printf '\e[0;32m[INFO]\e[0m Installing the %s release binary (linux/amd64, verified)' "$REL_TAG")"
    cmp "$out" "${BATS_TEST_TMPDIR}/rel"
    [[ ! -e "$B" ]]
    refute_called '^sudo '
    refute_called '^go '
    # Unverifiable: the reason and the build, into <out>.
    echo "# tampered" >> "${RELDIR}/tacctl-${REL_TAG}-linux-amd64"
    run --separate-stderr "${T}/bin/tacctl.sh" --install-binary "$out"
    assert_success
    assert_line --index 0 --partial "Release binary for ${REL_TAG} not used (tacctl-${REL_TAG}-linux-amd64 does not match SHA256SUMS); building from source."
    assert_line --index 1 --partial "Building ${out} from ${T}..."
    run "$out" x
    assert_output "NEW x"
    # A failed build: exit 1, <out> as it was, no Decision 20 text (the Go
    # side prints its own).
    go_toolchain "$GOROOT_DIR" 1.26.2 "boom"
    run "${T}/bin/tacctl.sh" --install-binary "$out"
    assert_failure 1
    refute_output --partial "way back"
    refute_output --partial "could not be built"
    run "$out" x
    assert_output "NEW x"
    [[ ! -e "$B" && ! -e "${out}.new" ]]
}

@test "shim: --verify-release passes on signed assets and fails on a flipped byte, another key, or no key" {
    release_tree
    fake_release_binary "${BATS_TEST_TMPDIR}/rel" "$HEAD_COMMIT"
    release_assets amd64 "${BATS_TEST_TMPDIR}/rel"
    run_shim --verify-release "$RELDIR"
    assert_success
    assert_output --partial "SHA256SUMS: good signature by tacctl-release."
    assert_output --partial "tacctl-${REL_TAG}-linux-amd64: built from ${HEAD_COMMIT}."
    assert_output --partial "Release assets in ${RELDIR} verified."
    # The allowed_signers file given.
    run_shim --verify-release "$RELDIR" "$TEST_SIGNERS"
    assert_success
    # Another key (the project's real one did not sign these test assets).
    run_shim --verify-release "$RELDIR" "${TACCTL_SRC}/release/allowed_signers"
    assert_failure 1
    assert_output --partial "SHA256SUMS.sig does not verify"
    # No key at all.
    printf '# comments only\n' > "${BATS_TEST_TMPDIR}/nokey_signers"
    run_shim --verify-release "$RELDIR" "${BATS_TEST_TMPDIR}/nokey_signers"
    assert_failure 1
    assert_output --partial "No release key in ${BATS_TEST_TMPDIR}/nokey_signers"
    # A flipped byte in the binary.
    local f="${RELDIR}/tacctl-${REL_TAG}-linux-amd64"
    printf '\x01' | dd of="$f" bs=1 seek=40 count=1 conv=notrunc status=none
    run_shim --verify-release "$RELDIR"
    assert_failure 1
    assert_output --partial "A file does not match SHA256SUMS"
    # A flipped byte in SHA256SUMS: the signature.
    release_assets amd64 "${BATS_TEST_TMPDIR}/rel"
    sed -i 's/^./0/' "${RELDIR}/SHA256SUMS"
    run_shim --verify-release "$RELDIR"
    assert_failure 1
    assert_output --partial "SHA256SUMS.sig does not verify"
    run_shim --verify-release
    assert_failure 1
    assert_output "Usage: tacctl.sh --verify-release <dir> [<allowed_signers>]"
}
