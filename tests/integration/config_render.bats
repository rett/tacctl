#!/usr/bin/env bats
# 'tacctl config render [--force]' through the real entrypoint: the store
# requirement, the drift gate, --force and its saved copy, and the DRIFT line
# in 'status' and 'config validate'.

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
    STORE="${TACCTL_STATE_DIR}/store.yaml"
    RENDERED="${TACCTL_STATE_DIR}/rendered.json"
    LEGACY_DIR="${TACCTL_STATE_DIR}/backups/legacy"
    GOLDEN="${TACCTL_SRC}/tests/fixtures/golden/tacquito.multiscope.rendered.yaml"
}

# A store plus the tacquito.yaml tacctl rendered from it, recorded.
rendered_install() {
    cp "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "$STORE"
    "$TACCTL_BIN_SCRIPT" config render > /dev/null
}

saved_copies() {
    find "$LEGACY_DIR" -name 'tacquito.yaml.drift.*' 2>/dev/null | sort
}

@test "config render: refused in legacy mode (no store); tacquito.yaml is not touched" {
    place_fixture tacquito.multiscope.yaml
    run "$TACCTL_BIN_SCRIPT" config render
    assert_failure 1
    assert_output --partial "store not initialised"
    run "$TACCTL_BIN_SCRIPT" config render --force
    assert_failure 1
    cmp "$TACCTL_CONFIG" "${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml"
    [[ ! -e "$RENDERED" ]]
    ! stub_called 'systemctl restart'
}

@test "config render: writes the config when there is none, records it, restarts the daemon" {
    cp "${TACCTL_SRC}/tests/fixtures/store.multiscope.yaml" "$STORE"
    run "$TACCTL_BIN_SCRIPT" config render
    assert_success
    assert_output --partial "Rendered ${TACCTL_CONFIG}, ${TACCTL_OVERRIDE_DIR}/tacctl.conf."
    cmp "$TACCTL_CONFIG" "$GOLDEN"
    [[ "$(stat -c %a "$TACCTL_CONFIG")" == "640" ]]
    [[ "$(stat -c %a "$RENDERED")" == "600" ]]
    stub_called 'chown tacquito:tacquito'
    stub_called 'systemctl restart tacquito'
    run find "$TACCTL_ETC" -mindepth 1
    assert_output "$TACCTL_CONFIG"
}

@test "config render: a second run changes nothing and does not restart" {
    rendered_install
    : > "$CALLS_LOG"
    run "$TACCTL_BIN_SCRIPT" config render
    assert_success
    assert_output --partial "already up to date"
    ! stub_called 'systemctl restart'
    [[ -z "$(saved_copies)" ]]
}

@test "config render: a store change is rendered without --force when the file is as tacctl left it" {
    rendered_install
    sed -i 's/juniper_class: OP-CLASS/juniper_class: OPS/' "$STORE"
    run "$TACCTL_BIN_SCRIPT" config render
    assert_success
    assert_output --partial "Rendered ${TACCTL_CONFIG}, ${TACCTL_OVERRIDE_DIR}/tacctl.conf."
    grep -q 'values: \["OPS"\]' "$TACCTL_CONFIG"
    [[ -z "$(saved_copies)" ]]
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    refute_output --partial "DRIFT"
}

@test "config render: refuses to overwrite a hand-edited file; --force overwrites and keeps a copy" {
    rendered_install
    echo "# hand edit" >> "$TACCTL_CONFIG"
    # Something to render: without a pending change there would still be the
    # edit to discard, so the refusal does not depend on this.
    cp "$TACCTL_CONFIG" "${BATS_TEST_TMPDIR}/edited.yaml"
    : > "$CALLS_LOG"

    run "$TACCTL_BIN_SCRIPT" config render
    assert_failure 3
    assert_output --partial "was edited since tacctl rendered it"
    assert_output --partial "tacctl config render --force"
    cmp "$TACCTL_CONFIG" "${BATS_TEST_TMPDIR}/edited.yaml"
    [[ -z "$(saved_copies)" ]]
    ! stub_called 'systemctl restart'

    run "$TACCTL_BIN_SCRIPT" config render --force
    assert_success
    assert_output --partial "Previous ${TACCTL_CONFIG} saved to ${LEGACY_DIR}/tacquito.yaml.drift."
    cmp "$TACCTL_CONFIG" "$GOLDEN"
    [[ "$(saved_copies | wc -l)" == "1" ]]
    cmp "$(saved_copies)" "${BATS_TEST_TMPDIR}/edited.yaml"
    [[ "$(stat -c %a "$(saved_copies)")" == "600" ]]
    stub_called 'systemctl restart tacquito'

    run "$TACCTL_BIN_SCRIPT" config render
    assert_success
    assert_output --partial "already up to date"
}

@test "config render: refuses to replace a file tacctl never rendered; --force saves it first" {
    # The state right after 'store import' on an existing install: a store,
    # and a tacquito.yaml written by the old editors.
    place_fixture tacquito.multiscope.yaml
    "$TACCTL_BIN_SCRIPT" store import > /dev/null
    run "$TACCTL_BIN_SCRIPT" config render
    assert_failure 3
    assert_output --partial "was not rendered by tacctl"
    cmp "$TACCTL_CONFIG" "${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml"
    [[ ! -e "$RENDERED" ]]

    run "$TACCTL_BIN_SCRIPT" config render --force
    assert_success
    cmp "$TACCTL_CONFIG" "$GOLDEN"
    # The import already kept the file as the pre-store config; the forced
    # render says so instead of saving a second, identical copy.
    assert_output --partial "is already kept as ${LEGACY_DIR}/tacquito.yaml.pre-store."
    [[ -z "$(saved_copies)" ]]
    cmp "${LEGACY_DIR}"/tacquito.yaml.pre-store.* "${TACCTL_SRC}/tests/fixtures/tacquito.multiscope.yaml"
}

@test "config render: an unrecorded file that already equals the render is adopted, not refused" {
    rendered_install
    rm "$RENDERED"
    : > "$CALLS_LOG"
    run "$TACCTL_BIN_SCRIPT" config render
    assert_success
    assert_output --partial "already up to date"
    [[ -f "$RENDERED" ]]
    ! stub_called 'systemctl restart'
}

@test "config render: a deleted config is recreated without --force" {
    rendered_install
    rm "$TACCTL_CONFIG"
    run "$TACCTL_BIN_SCRIPT" config render
    assert_success
    assert_output --partial "Rendered ${TACCTL_CONFIG}, ${TACCTL_OVERRIDE_DIR}/tacctl.conf."
    cmp "$TACCTL_CONFIG" "$GOLDEN"
    [[ -z "$(saved_copies)" ]]
}

@test "config render: unreadable render records refuse an overwrite" {
    rendered_install
    echo "{not json" > "$RENDERED"
    sed -i 's/juniper_class: OP-CLASS/juniper_class: OPS/' "$STORE"
    run "$TACCTL_BIN_SCRIPT" config render
    assert_failure 1
    assert_output --partial "refusing to overwrite"
    cmp "$TACCTL_CONFIG" "$GOLDEN"
}

@test "config render: a store that fails validation renders nothing" {
    rendered_install
    sed -i 's/group: operator/group: nosuch/' "$STORE"
    : > "$CALLS_LOG"
    run "$TACCTL_BIN_SCRIPT" config render
    assert_failure 1
    assert_output --partial "cannot render an invalid model"
    cmp "$TACCTL_CONFIG" "$GOLDEN"
    ! stub_called 'systemctl restart'
}

@test "config render: rejects unknown arguments" {
    rendered_install
    run "$TACCTL_BIN_SCRIPT" config render --now
    assert_failure 1
    assert_output --partial "Usage: tacctl config render [--force]"
}

@test "status and config validate: a red DRIFT line while the file is hand-edited, none otherwise" {
    rendered_install
    run "$TACCTL_BIN_SCRIPT" status
    refute_output --partial "DRIFT"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    refute_output --partial "DRIFT"

    echo "# hand edit" >> "$TACCTL_CONFIG"
    run "$TACCTL_BIN_SCRIPT" status
    assert_output --partial "DRIFT:"
    assert_output --partial "${TACCTL_CONFIG} — edited since tacctl rendered it"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_failure
    assert_output --partial "DRIFT:"
    assert_output --partial "tacctl config render --force"

    "$TACCTL_BIN_SCRIPT" config render --force > /dev/null
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    refute_output --partial "DRIFT"
}

@test "status and config validate: no DRIFT line on an install that never rendered" {
    place_fixture tacquito.multiscope.yaml
    run "$TACCTL_BIN_SCRIPT" status
    refute_output --partial "DRIFT"
    run "$TACCTL_BIN_SCRIPT" config validate
    refute_output --partial "DRIFT"
}

# --- the renderer behind every mutating command -------------------------------

@test "round trip: the file left by a run of mutating commands re-imports as the store that rendered it" {
    # Every command below writes the store and re-renders. The rendered file
    # must then say exactly what the store says: importing it and rendering
    # the import changes nothing the daemon acts on, and replacing the store
    # with that import changes nothing in the store.
    local hash="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"
    rendered_install
    run "$TACCTL_BIN_SCRIPT" group add helpdesk 5 HELPDESK-CLASS
    assert_success
    run "$TACCTL_BIN_SCRIPT" group commands add helpdesk show --match '^version$' --action permit
    assert_success
    run "$TACCTL_BIN_SCRIPT" group commands add operator configure --action deny
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope add edge --prefixes 192.168.40.0/24,2001:db8::/32 --secret edge-secret-0123456789abcdef
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope prefixes prod add 10.10.0.0/16
    assert_success
    run "$TACCTL_BIN_SCRIPT" scope secret dmz set rotated-secret-0123456789abc
    assert_success
    run "$TACCTL_BIN_SCRIPT" user add dave helpdesk --hash "$hash" --scopes edge,prod-inner
    assert_success
    run "$TACCTL_BIN_SCRIPT" user add erin readonly --hash "$hash" --scopes lab
    assert_success
    run "$TACCTL_BIN_SCRIPT" user disable erin
    assert_success
    run "$TACCTL_BIN_SCRIPT" user scope carol add edge
    assert_success
    run "$TACCTL_BIN_SCRIPT" user remove bob <<< "y"
    assert_success
    run "$TACCTL_BIN_SCRIPT" config deny add 10.66.0.0/16
    assert_success
    run "$TACCTL_BIN_SCRIPT" config allow add 10.0.0.0/8,192.168.0.0/16,2001:db8::/32
    assert_success

    # No command left the file and the store apart, or the file unrecorded.
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
    refute_output --partial "DRIFT"
    run "$TACCTL_BIN_SCRIPT" config render
    assert_output --partial "already up to date"

    run "$TACCTL_BIN_SCRIPT" store import --check
    assert_success
    assert_output --partial "Groups:   4"
    assert_output --partial "Users:    4 (1 disabled)"
    assert_output --partial "Scopes:   5"
    assert_output --partial "Filters:  allow 3, deny 1"
    assert_output --partial "    EQUIVALENT"
    refute_output --partial "never matches a client"

    cp "$STORE" "${BATS_TEST_TMPDIR}/store.before"
    run "$TACCTL_BIN_SCRIPT" store import --replace
    assert_success
    diff -u "${BATS_TEST_TMPDIR}/store.before" "$STORE"
}
