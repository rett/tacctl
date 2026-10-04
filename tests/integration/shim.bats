#!/usr/bin/env bats
# The bootstrap shim (bin/tacctl.sh; docs/plans/go-rewrite.md 5.2): its own rows of the offline and
# partial-failure matrix, which the Go tests of internal/lifecycle cannot
# reach because they are bash. A copy of the shim runs from a scratch tree
# with TACCTL_TEST_ROOT, so /usr/local/bin/tacctl and /usr/local/go are
# under the test's directory; git, wget and the Go toolchain are stand-ins.
# Nothing here runs the Go binary.

load ../helpers/setup
load ../helpers/mocks

bats_require_minimum_version 1.5.0

SHIM="${TACCTL_SRC}/bin/tacctl.sh"
HEAD_COMMIT="2222222222222222222222222222222222222222"
OLD_COMMIT="1111111111111111111111111111111111111111"

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
  *) cp "'"${BATS_TEST_TMPDIR}/go.tgz"'" "$3" ;;
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
    stub_called '^wget -q -O .*/go1\.26\.2\.linux-amd64\.tar\.gz https://dl\.google\.com/go/go1\.26\.2\.linux-amd64\.tar\.gz$'
    stub_called '^wget -qO- https://dl\.google\.com/go/go1\.26\.2\.linux-amd64\.tar\.gz\.sha256$'
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
  *) cp "'"${BATS_TEST_TMPDIR}/go.tgz"'" "$3" ;;
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
  *) cp "'"${BATS_TEST_TMPDIR}/go.tgz"'" "$3" ;;
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
    assert_output "Usage: tacctl.sh --build <out> [--tags <tags>]"
    run_shim --build "${BATS_TEST_TMPDIR}/out/tacctl" --tags testknobs
    assert_success
    [[ -x "${BATS_TEST_TMPDIR}/out/tacctl" && ! -e "$B" ]]
    stub_called '^go build -trimpath -buildvcs=false -tags testknobs '
}

@test "shim: one build recipe: --build, the install path, 'make build' and the Go upgrade use it" {
    # Defined once, called by '--build' and by the install path.
    [[ "$(grep -c '^tacctl_go_build() {$' "$SHIM")" -eq 1 ]]
    [[ "$(grep -cE '^[[:space:]]*tacctl_go_build ' "$SHIM")" -eq 2 ]]
    # 'make build' is '--build' with the test knobs.
    grep -qE '^[[:space:]]+bin/tacctl\.sh --build dist/tacctl --tags testknobs$' "${TACCTL_SRC}/Makefile"
    # The Go upgrade and install rebuild the command with '<deploy>/bin/tacctl.sh --build <command>'.
    grep -qE 'filepath\.Join\([^)]*"bin", "tacctl\.sh"\)' "${TACCTL_SRC}/internal/lifecycle/build.go"
    grep -q '"--build"' "${TACCTL_SRC}/internal/lifecycle/build.go"
}
