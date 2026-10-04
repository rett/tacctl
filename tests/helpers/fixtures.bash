#!/usr/bin/env bash
# Fixture helpers: load YAML fixtures into $TACCTL_CONFIG, diff against golden files.

# place_fixture <fixture-name>
# Copies tests/fixtures/<fixture-name> (a file or dir relative to tests/fixtures/)
# into $TACCTL_CONFIG or $TACCTL_ETC depending on type, and does nothing else.
# Use it directly only when the test needs the state dir left alone: tests of
# the importer itself and of the no-store (legacy) read path. Everything else
# wants load_fixture.
place_fixture() {
    local name="$1"
    local src="${TACCTL_SRC}/tests/fixtures/${name}"
    if [[ -f "${src}" ]]; then
        cp "${src}" "${TACCTL_CONFIG}"
    elif [[ -d "${src}" ]]; then
        cp -r "${src}"/. "${TACCTL_ETC}/"
    else
        echo "place_fixture: ${src} not found" >&2
        return 1
    fi
}

# load_fixture <fixture-name>
# place_fixture, then, for a tacquito.*.yaml fixture, seed the store
# ($TACCTL_STATE_DIR/store.yaml) from it with a strict 'tacctl store import'
# (never --force). A fixture the importer rejects fails the calling test with
# the importer's report. Loading a second tacquito.*.yaml replaces the first:
# the file and the store both follow the most recent fixture.
load_fixture() {
    place_fixture "$1" || return 1
    case "$1" in
        tacquito.*.yaml) seed_store_from_fixture "$1" ;;
    esac
}

# load_store_fixture <fixture-name>
# Places tests/fixtures/<fixture-name> (store.X.yaml) directly as
# $TACCTL_STATE_DIR/store.yaml, mode 0600. It does not touch tacquito.yaml.
load_store_fixture() {
    local src="${TACCTL_SRC}/tests/fixtures/$1"
    if [[ ! -f "${src}" ]]; then
        echo "load_store_fixture: ${src} not found" >&2
        return 1
    fi
    mkdir -p "${TACCTL_STATE_DIR}" || return 1
    cp "${src}" "${TACCTL_STATE_DIR}/store.yaml" || return 1
    chmod 600 "${TACCTL_STATE_DIR}/store.yaml"
    _fixture_model_reset
}

# seed_store_from_fixture <tacquito.X.yaml>
# Writes $TACCTL_STATE_DIR/store.yaml as 'tacctl store import' would from that
# fixture. The importer runs once per distinct fixture content per bats run,
# in a scratch state dir, and the result is cached under $BATS_RUN_TMPDIR; later
# loads of the same fixture just copy it. The seed is the store file and
# nothing else (no lock file, no snapshot, no output).
#
# The importer also reads password-date and disabled-hash sidecars from the
# state dir, so a test that planted any before loading gets a direct import
# instead of the cached result.
seed_store_from_fixture() {
    local name="$1"
    local src="${TACCTL_SRC}/tests/fixtures/${name}"
    local store="${TACCTL_STATE_DIR}/store.yaml"
    rm -f "${store}"
    mkdir -p "${TACCTL_STATE_DIR}" || return 1

    local out rc=0
    if _fixture_has_sidecars; then
        out=$("${TACCTL_BIN_SCRIPT}" store import "${src}" 2>&1) || rc=$?
        if (( rc != 0 )); then
            _fixture_seed_failed "${name}" "${rc}" "${out}"
            return 1
        fi
        rm -f "${TACCTL_STATE_DIR}/.store.lock"
        _fixture_model_reset
        return 0
    fi

    local cache="${BATS_RUN_TMPDIR:-${BATS_FILE_TMPDIR:-${BATS_TEST_TMPDIR}}}/store-seed"
    local key cached
    key=$(sha256sum "${src}" | cut -c1-16) || return 1
    cached="${cache}/${name}.${key}.yaml"
    if [[ ! -f "${cached}" ]]; then
        mkdir -p "${cache}" || return 1
        local scratch
        scratch=$(mktemp -d "${cache}/work.XXXXXX") || return 1
        mkdir -p "${scratch}/state"
        out=$(TACCTL_STATE_DIR="${scratch}/state" "${TACCTL_BIN_SCRIPT}" store import "${src}" 2>&1) || rc=$?
        if (( rc != 0 )) || [[ ! -f "${scratch}/state/store.yaml" ]]; then
            rm -rf "${scratch}"
            _fixture_seed_failed "${name}" "${rc}" "${out}"
            return 1
        fi
        # Atomic publish; concurrent bats jobs may race here and either wins.
        mv -f "${scratch}/state/store.yaml" "${cached}.$$" && mv -f "${cached}.$$" "${cached}"
        rm -rf "${scratch}"
    fi
    cp "${cached}" "${store}" || return 1
    chmod 600 "${store}"
    _fixture_model_reset
}

_fixture_has_sidecars() {
    local f
    for f in "${TACCTL_STATE_DIR}"/backups/password-dates/*.date \
             "${TACCTL_STATE_DIR}"/backups/disabled/*.hash; do
        [[ -e "${f}" ]] && return 0
    done
    return 1
}

_fixture_seed_failed() {
    {
        echo "load_fixture: 'tacctl store import' rejected tests/fixtures/$1 (exit $2)."
        echo "A tacquito.*.yaml fixture must import without --force; fix the fixture,"
        echo "or name it legacy.*.yaml and place it with place_fixture."
        printf '%s\n' "$3"
    } >&2
}

# Unit tests source the library into the test shell; drop its cached model so
# the next read sees the file just written. No-op for subprocess tests.
_fixture_model_reset() {
    if declare -F _model_invalidate > /dev/null; then
        _model_invalidate
    fi
    return 0
}

# golden_diff <actual-file> <golden-relpath>
# Compares <actual-file> against tests/fixtures/golden/<golden-relpath>.
# Set UPDATE_GOLDEN=1 to regenerate the golden file instead of comparing.
golden_diff() {
    local actual="$1"
    local golden="${TACCTL_SRC}/tests/fixtures/golden/$2"
    if [[ "${UPDATE_GOLDEN:-0}" == "1" ]]; then
        mkdir -p "$(dirname "${golden}")"
        cp "${actual}" "${golden}"
        return 0
    fi
    if [[ ! -f "${golden}" ]]; then
        echo "golden_diff: ${golden} missing. Run with UPDATE_GOLDEN=1 to create." >&2
        return 1
    fi
    diff -u "${golden}" "${actual}"
}

# rendered_record <file>...: record each file in $TACCTL_STATE_DIR/rendered.json
# as tacctl rendered it (its sha256), the way a render does; rendered_forget
# <file>... drops the records. For tests that plant a state an earlier
# release left. The file is written as tacctl writes it: indent 2, keys
# sorted, mode 0600.
rendered_record() {
    local f
    for f in "$@"; do
        _rendered_edit "$f" "$(sha256sum < "$f" | cut -d' ' -f1)" || return 1
    done
}

rendered_forget() {
    local f
    for f in "$@"; do
        _rendered_edit "$f" "" || return 1
    done
}

_rendered_edit() {
    local json="${TACCTL_STATE_DIR}/rendered.json" key="$1" val="$2" line k n=0
    local -A rec=()
    local re='^  "(.*)": "([0-9a-f]*)",?$'
    if [[ -f "$json" ]]; then
        while IFS= read -r line; do
            [[ "$line" =~ $re ]] && rec["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
        done < "$json"
    fi
    if [[ -n "$val" ]]; then
        rec["$key"]="$val"
    else
        unset 'rec[$key]'
    fi
    {
        if [[ ${#rec[@]} -eq 0 ]]; then
            echo '{}'
        else
            echo '{'
            while IFS= read -r k; do
                n=$((n + 1))
                if [[ $n -lt ${#rec[@]} ]]; then
                    printf '  "%s": "%s",\n' "$k" "${rec[$k]}"
                else
                    printf '  "%s": "%s"\n' "$k" "${rec[$k]}"
                fi
            done < <(printf '%s\n' "${!rec[@]}" | LC_ALL=C sort)
            echo '}'
        fi
    } > "${json}.new" && chmod 600 "${json}.new" && mv -f "${json}.new" "$json"
}
