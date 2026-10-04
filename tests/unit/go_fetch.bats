#!/usr/bin/env bats
# Unit tests for _go_tarball_fetch (lib/backends/tacacs.sh): the Go tarball
# that 'tacctl install' builds tacquito with is downloaded from dl.google.com
# and installed only once verified against the published SHA-256.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    tacctl_source_lib
    DL="${BATS_TEST_TMPDIR}/dl"
    mkdir -p "$DL"
    TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
    URL="https://dl.google.com/go/${TARBALL}"
    # The stub's tarball content and its digest.
    export TAR_BODY="fake go ${GO_VERSION} tarball"
    GOOD_SUM=$(printf '%s\n' "$TAR_BODY" | sha256sum | awk '{print $1}')
    # wget stand-in. "-q -O <file> <url>" writes $TAR_BODY to <file>, or
    # leaves it empty and exits $TAR_RC when that is set; "-qO- <url>.sha256"
    # prints $SUM_BODY, or exits $SUM_RC when that is set.
    stub_cmd wget '
url="${*: -1}"
case "$url" in
    *.sha256)
        [[ -n "${SUM_RC:-}" ]] && exit "$SUM_RC"
        printf "%s" "${SUM_BODY:-}" ;;
    *)
        out=""
        while (( $# )); do [[ "$1" == -O ]] && out="$2"; shift; done
        : > "$out"
        [[ -n "${TAR_RC:-}" ]] && exit "$TAR_RC"
        printf "%s\n" "$TAR_BODY" > "$out" ;;
esac'
}

# Both downloads came from dl.google.com, the tarball into $DL.
assert_urls() {
    stub_called "^wget -q -O ${DL}/${TARBALL} ${URL}\$"
    stub_called "^wget -qO- ${URL}.sha256\$"
    run grep -c "go\.dev" "$CALLS_LOG"
    assert_output "0"
}

@test "_go_tarball_fetch: a tarball matching the published checksum is kept" {
    export SUM_BODY="${GOOD_SUM}"$'\n'
    run _go_tarball_fetch "$DL"
    assert_success
    assert_output --partial "Go tarball checksum verified."
    assert_file_exists "${DL}/${TARBALL}"
    assert_urls
}

@test "_go_tarball_fetch: a checksum mismatch removes the tarball and fails" {
    export SUM_BODY="$(printf '0%.0s' {1..64})"
    run _go_tarball_fetch "$DL"
    assert_failure
    assert_output --partial "Go tarball checksum mismatch!"
    assert_output --partial "  Expected: $(printf '0%.0s' {1..64})"
    assert_output --partial "  Got:      ${GOOD_SUM}"
    refute_output --partial "verified"
    assert_file_not_exists "${DL}/${TARBALL}"
    assert_urls
}

@test "_go_tarball_fetch: a checksum that cannot be fetched refuses to install" {
    export SUM_RC=8
    run _go_tarball_fetch "$DL"
    assert_failure
    assert_output --partial "Could not fetch the Go checksum from ${URL}.sha256; Go was not installed because it could not be verified."
    refute_output --partial "Go tarball checksum verified."
    assert_file_not_exists "${DL}/${TARBALL}"
    assert_urls
}

@test "_go_tarball_fetch: a checksum URL that answers with a web page refuses to install" {
    export SUM_BODY=$'<!DOCTYPE html>\n<html><body>Downloads</body></html>\n'
    run _go_tarball_fetch "$DL"
    assert_failure
    assert_output --partial "Could not fetch the Go checksum from ${URL}.sha256; Go was not installed because it could not be verified."
    refute_output --partial "checksum mismatch"
    assert_file_not_exists "${DL}/${TARBALL}"
    assert_urls
}

@test "_go_tarball_fetch: a failed tarball download is an error" {
    export TAR_RC=8 SUM_BODY="$GOOD_SUM"
    run _go_tarball_fetch "$DL"
    assert_failure
    assert_output --partial "Could not download ${URL}; Go was not installed."
    assert_file_not_exists "${DL}/${TARBALL}"
    stub_called "^wget -q -O ${DL}/${TARBALL} ${URL}\$"
    # No checksum is fetched for a tarball that is not there.
    run grep -c "sha256" "$CALLS_LOG"
    assert_output "0"
}
