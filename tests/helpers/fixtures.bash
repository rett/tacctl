#!/usr/bin/env bash
# Fixture helpers: load YAML fixtures into $TACCTL_CONFIG, diff against golden files.

# load_fixture <fixture-name>
# Copies tests/fixtures/<fixture-name> (a file or dir relative to tests/fixtures/)
# into $TACCTL_CONFIG or $TACCTL_ETC depending on type.
load_fixture() {
    local name="$1"
    local src="${TACCTL_SRC}/tests/fixtures/${name}"
    if [[ -f "${src}" ]]; then
        cp "${src}" "${TACCTL_CONFIG}"
    elif [[ -d "${src}" ]]; then
        cp -r "${src}"/. "${TACCTL_ETC}/"
    else
        echo "load_fixture: ${src} not found" >&2
        return 1
    fi
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
