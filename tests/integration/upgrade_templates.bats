#!/usr/bin/env bats
# The device config templates in the state directory on install and upgrade
# (templates_sync, lib/lifecycle.sh): a template tacctl wrote and the
# operator left alone follows the release; a customised one is kept, with
# the release's version beside it as <name>.template.new and a warning.
#
# What tacctl wrote is recorded in templates/.shipped.sha256. An install
# from before that manifest is judged against the history of the tree the
# templates come from (the management repo, a git clone): a file that is
# some version tacctl shipped is tacctl's. The tree here is a scratch git
# repo with two releases of cisco.template.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger
    tacctl_source_lib
    TREE="${BATS_TEST_TMPDIR}/deploy"
    TDIR="${TACCTL_STATE_DIR}/templates"
    MANIFEST="${TDIR}/.shipped.sha256"
    CISCO="${TDIR}/cisco.template"
    OUT="${BATS_TEST_TMPDIR}/sync.out"
    V1_CISCO='hostname ${SERVER_IP} -- release 1'
    V2_CISCO='hostname ${SERVER_IP} -- release 2'
    JUNIPER='set system tacplus-server ${SERVER_IP} secret ${SECRET}'
    mkdir -p "${TREE}/config/templates"
    git -C "$TREE" init -q
    release "$V1_CISCO"
}

# --- helpers ---

# Commit a release of the tree: cisco.template with the given content, and
# juniper.template (the same in every release).
release() {
    printf '%s\n' "$1" > "${TREE}/config/templates/cisco.template"
    printf '%s\n' "$JUNIPER" > "${TREE}/config/templates/juniper.template"
    git -C "$TREE" add -A
    git -C "$TREE" -c user.name=t -c user.email=t@example.com commit -q -m "release" --allow-empty
}

# Run templates_sync in this shell (SCRIPTS_UPDATED and TEMPLATES_CUSTOMISED
# stay readable); its output, colours stripped, lands in OUT.
sync_templates() {
    SCRIPTS_UPDATED=0
    templates_sync "$TREE" > "$OUT" 2>&1
    sed -i 's/\x1b\[[0-9;]*m//g' "$OUT"
}

sha() { sha256sum < "$1" | cut -d' ' -f1; }

# The manifest's record for <name>, '' when it has none.
recorded() { awk -v n="$1" '$2 == n { print $1 }' "$MANIFEST"; }

# The templates directory as an install from before the manifest left it.
pre_manifest_install() {
    mkdir -p "$TDIR"
    printf '%s\n' "$1" > "$CISCO"
    printf '%s\n' "$JUNIPER" > "${TDIR}/juniper.template"
}

# --- install ---------------------------------------------------------------

@test "install: the templates are seeded and every one is recorded in the manifest" {
    rm -rf "$TDIR"
    sync_templates
    cmp "$CISCO" "${TREE}/config/templates/cisco.template"
    cmp "${TDIR}/juniper.template" "${TREE}/config/templates/juniper.template"
    grep -qxF "[INFO]   Installed: template: cisco.template" "$OUT"
    [[ "$SCRIPTS_UPDATED" == 2 ]]
    # sha256sum's own format: the operator can check it with 'sha256sum -c'.
    (cd "$TDIR" && sha256sum -c --quiet .shipped.sha256)
    [[ "$(wc -l < "$MANIFEST")" == 2 ]]
    [[ -z "$(find "$TDIR" -name '*.new')" ]]
    [[ ${#TEMPLATES_CUSTOMISED[@]} == 0 ]]
}

@test "install over a templates directory that is already there keeps a customised template" {
    pre_manifest_install "my own cisco"
    sync_templates
    [[ "$(cat "$CISCO")" == "my own cisco" ]]
    cmp "${CISCO}.new" "${TREE}/config/templates/cisco.template"
    [[ -z "$(recorded cisco.template)" ]]
    [[ "$(recorded juniper.template)" == "$(sha "${TDIR}/juniper.template")" ]]
}

# --- upgrade with a manifest ------------------------------------------------

@test "upgrade: a template the operator did not modify follows the release" {
    sync_templates
    release "$V2_CISCO"
    sync_templates
    [[ "$(cat "$CISCO")" == "$V2_CISCO" ]]
    grep -qxF "[INFO]   Updated: template: cisco.template" "$OUT"
    grep -qxF "[INFO]   Unchanged: template: juniper.template" "$OUT"
    ! grep -q WARN "$OUT"
    [[ "$SCRIPTS_UPDATED" == 1 ]]
    [[ "$(recorded cisco.template)" == "$(sha "$CISCO")" ]]
    [[ ! -e "${CISCO}.new" ]]
    [[ ${#TEMPLATES_CUSTOMISED[@]} == 0 ]]
}

@test "upgrade: a customised template is kept; the release's version goes beside it as .new, with a warning saying how to compare" {
    sync_templates
    local v1_sum
    v1_sum=$(recorded cisco.template)
    printf 'my own cisco\n' > "$CISCO"
    # A .new from an earlier release is replaced by this one's.
    printf 'stale\n' > "${CISCO}.new"
    release "$V2_CISCO"
    sync_templates
    [[ "$(cat "$CISCO")" == "my own cisco" ]]
    cmp "${CISCO}.new" "${TREE}/config/templates/cisco.template"
    grep -qxF "[WARN]   Customised template kept: ${CISCO}" "$OUT"
    grep -qxF "[WARN]     This release's version is beside it: ${CISCO}.new" "$OUT"
    grep -qF "Compare: diff ${CISCO} ${CISCO}.new" "$OUT"
    [[ "${TEMPLATES_CUSTOMISED[*]}" == "cisco.template" ]]
    [[ "$SCRIPTS_UPDATED" == 0 ]]
    # The record still says what tacctl last wrote there.
    [[ "$(recorded cisco.template)" == "$v1_sum" ]]
    # The .new is never used: the customised template still resolves.
    [[ "$(resolve_template cisco)" == "$CISCO" ]]
}

@test "upgrade: re-running changes nothing; the only output beyond 'Unchanged' is the still-customised notice" {
    sync_templates
    printf 'my own cisco\n' > "$CISCO"
    release "$V2_CISCO"
    sync_templates
    touch -d '1 minute ago' "${BATS_TEST_TMPDIR}/mark"
    find "$TDIR" -exec touch -d '2 minutes ago' {} +
    local before
    before=$(cd "$TDIR" && find . -type f -printf '%p %i %T@ %s\n' | sort)
    sync_templates
    [[ "$(cd "$TDIR" && find . -type f -printf '%p %i %T@ %s\n' | sort)" == "$before" ]]
    [[ -z "$(find "$TDIR" -newer "${BATS_TEST_TMPDIR}/mark")" ]]
    [[ "$SCRIPTS_UPDATED" == 0 ]]
    run grep -vE '^\[INFO\]   Unchanged: template: |^\[WARN\]   Customised template kept: |^\[WARN\]     (This release|Compare)' "$OUT"
    assert_output ""
    [[ "$(grep -c 'Customised template kept' "$OUT")" == 1 ]]
}

@test "upgrade: a customised template that is brought back to the shipped one is recorded again and its .new goes" {
    sync_templates
    printf 'my own cisco\n' > "$CISCO"
    release "$V2_CISCO"
    sync_templates
    mv "${CISCO}.new" "$CISCO"
    sync_templates
    ! grep -q WARN "$OUT"
    [[ "$(recorded cisco.template)" == "$(sha "$CISCO")" ]]
    [[ ! -e "${CISCO}.new" ]]
    # And from then on it follows the release again.
    release 'hostname ${SERVER_IP} -- release 3'
    sync_templates
    grep -qxF "[INFO]   Updated: template: cisco.template" "$OUT"
}

# --- upgrade from a release before the manifest ------------------------------

@test "manifest-less: a template that is an older shipped version is refreshed, and the manifest is written" {
    pre_manifest_install "$V1_CISCO"
    release "$V2_CISCO"
    [[ ! -e "$MANIFEST" ]]
    sync_templates
    [[ "$(cat "$CISCO")" == "$V2_CISCO" ]]
    grep -qxF "[INFO]   Updated: template: cisco.template" "$OUT"
    ! grep -q WARN "$OUT"
    [[ ! -e "${CISCO}.new" ]]
    (cd "$TDIR" && sha256sum -c --quiet .shipped.sha256)
    [[ "$(wc -l < "$MANIFEST")" == 2 ]]
}

@test "manifest-less: a customised template is kept, with .new and the warning" {
    pre_manifest_install "my own cisco"
    release "$V2_CISCO"
    sync_templates
    [[ "$(cat "$CISCO")" == "my own cisco" ]]
    cmp "${CISCO}.new" "${TREE}/config/templates/cisco.template"
    grep -qxF "[WARN]   Customised template kept: ${CISCO}" "$OUT"
    [[ "${TEMPLATES_CUSTOMISED[*]}" == "cisco.template" ]]
    # Nothing is recorded for it; the unmodified one is.
    [[ -z "$(recorded cisco.template)" ]]
    [[ -n "$(recorded juniper.template)" ]]
}

@test "manifest-less without git history: a template that differs from the shipped one counts as customised" {
    pre_manifest_install "$V1_CISCO"
    release "$V2_CISCO"
    rm -rf "${TREE}/.git"
    sync_templates
    [[ "$(cat "$CISCO")" == "$V1_CISCO" ]]
    cmp "${CISCO}.new" "${TREE}/config/templates/cisco.template"
    grep -qxF "[WARN]   Customised template kept: ${CISCO}" "$OUT"
}

@test "a template that is some other template's shipped content is not taken for a shipped version of its own" {
    pre_manifest_install "$JUNIPER"
    release "$V2_CISCO"
    sync_templates
    [[ "$(cat "$CISCO")" == "$JUNIPER" ]]
    [[ "${TEMPLATES_CUSTOMISED[*]}" == "cisco.template" ]]
}

# --- what reads the directory -------------------------------------------------

@test "neither the manifest nor a .new file is a template: resolution and *.template globs skip them" {
    sync_templates
    printf 'my own cisco\n' > "$CISCO"
    release "$V2_CISCO"
    sync_templates
    [[ -e "${CISCO}.new" && -e "$MANIFEST" ]]
    run bash -c 'cd "$1" && printf "%s\n" *.template' _ "$TDIR"
    assert_output "$(printf 'cisco.template\njuniper.template')"
    # A .new without the template itself does not resolve; the shipped one does.
    rm "$CISCO"
    [[ "$(resolve_template cisco)" == "${TEMPLATE_DIR_REPO}/cisco.template" ]]
}

@test "uninstall removes the manifest and the .new files with the state directory" {
    [[ "$TEMPLATE_DIR_LOCAL" == "${TACCTL_STATE_DIR}/templates" ]]
    run bash -c 'source "$1"; declare -f cmd_uninstall' _ "$TACCTL_BIN_SCRIPT"
    assert_output --partial 'rm -rf "${TACCTL_STATE_DIR:?}"'
}

