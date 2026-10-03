#!/usr/bin/env bats
# Integration tests for `tacctl scope protocols <name> [list|set <csv>|clear]`:
# the per-scope filter naming which protocols serve a scope.

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
    load_fixture tacquito.multiscope.yaml
    STORE="${TACCTL_STATE_DIR}/store.yaml"
}

# The scope's protocols as stored: comma-joined, empty when there is no filter.
stored_protocols() {
    python3 -c '
import sys, yaml
with open(sys.argv[1]) as f:
    print(",".join(yaml.safe_load(f)["scopes"][sys.argv[2]].get("protocols") or []))' "$STORE" "$1"
}

# Scope names tacquito would load from the rendered config.
rendered_scopes() {
    python3 -c '
import sys, yaml
with open(sys.argv[1]) as f:
    print("\n".join(sorted({s["name"] for s in yaml.safe_load(f).get("secrets") or []})))' "$TACCTL_CONFIG"
}

@test "scope protocols: with no filter, list says every backend serves the scope" {
    run "$TACCTL_BIN_SCRIPT" scope protocols lab
    assert_success
    assert_output --partial "Scope 'lab' protocols: all"
    run "$TACCTL_BIN_SCRIPT" scope protocols lab list
    assert_success
    assert_output --partial "Scope 'lab' protocols: all"
    [[ -z "$(stored_protocols lab)" ]]
}

@test "scope protocols set: stores the filter; list and scope show print it" {
    run "$TACCTL_BIN_SCRIPT" scope protocols dmz set tacacs
    assert_success
    assert_output --partial "Scope 'dmz' protocols set to tacacs."
    [[ "$(stored_protocols dmz)" == "tacacs" ]]
    run "$TACCTL_BIN_SCRIPT" scope protocols dmz list
    assert_output --partial "Scope 'dmz' protocols: tacacs"
    run "$TACCTL_BIN_SCRIPT" scope show dmz
    assert_success
    assert_line --regexp 'Protocols:.* tacacs$'
    # A scope without a filter says so.
    run "$TACCTL_BIN_SCRIPT" scope show lab
    assert_line --regexp 'Protocols:.* all \(no filter\)$'
}

@test "scope protocols set: accepts a list in any order and stores it once each, in a fixed order" {
    run "$TACCTL_BIN_SCRIPT" scope protocols dmz set " radius , tacacs,radius"
    assert_success
    [[ "$(stored_protocols dmz)" == "tacacs,radius" ]]
    run "$TACCTL_BIN_SCRIPT" scope protocols dmz set tacacs,radius
    assert_success
    assert_output --partial "already tacacs,radius"
}

@test "scope protocols set: rejects a protocol the schema does not know, and an empty list" {
    cp "$STORE" "${BATS_TEST_TMPDIR}/before.yaml"
    run "$TACCTL_BIN_SCRIPT" scope protocols dmz set tacacs,ldap
    assert_failure
    assert_output --partial "Unknown protocol 'ldap'"
    assert_output --partial "tacacs, radius"
    run "$TACCTL_BIN_SCRIPT" scope protocols dmz set ","
    assert_failure
    assert_output --partial "No protocols given"
    run "$TACCTL_BIN_SCRIPT" scope protocols dmz set
    assert_failure
    assert_output --partial "Usage:"
    cmp "$STORE" "${BATS_TEST_TMPDIR}/before.yaml"
}

@test "scope protocols: the store's own schema refuses an unknown protocol" {
    tacctl_source_lib
    run store_scope_set dmz protocols=ldap
    assert_failure
    assert_output --partial "protocols must be a list drawn from: tacacs, radius"
    [[ -z "$(stored_protocols dmz)" ]]
}

@test "scope protocols set radius: TACACS+ stops serving the scope and its users' grant of it" {
    [[ "$(rendered_scopes)" == *"dmz"* ]]
    run "$TACCTL_BIN_SCRIPT" scope protocols dmz set radius
    assert_success
    assert_output --partial "no longer served over TACACS+"
    stub_called 'systemctl restart tacquito'

    # Gone from the rendered config: no secrets[] entry, and carol (lab, dmz)
    # keeps only lab there.
    run rendered_scopes
    refute_line "dmz"
    assert_line "lab"
    run grep -A2 '^  - name: carol$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["lab"]'
    run grep -c 'dmz-secret' "$TACCTL_CONFIG"
    assert_output "0"

    # Still a scope, with its users, in the store and in every listing.
    run "$TACCTL_BIN_SCRIPT" scope list
    assert_output --partial "dmz"
    run "$TACCTL_BIN_SCRIPT" user scope carol list
    assert_output --partial "- dmz"
    run "$TACCTL_BIN_SCRIPT" config validate
    assert_success
}

@test "scope protocols clear: removes the filter and TACACS+ serves the scope again" {
    "$TACCTL_BIN_SCRIPT" scope protocols dmz set radius > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope protocols dmz clear
    assert_success
    assert_output --partial "filter cleared"
    [[ -z "$(stored_protocols dmz)" ]]
    run rendered_scopes
    assert_line "dmz"
    run grep -A2 '^  - name: carol$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["lab", "dmz"]'

    run "$TACCTL_BIN_SCRIPT" scope protocols dmz clear
    assert_success
    assert_output --partial "has no protocols filter"
}

@test "scope protocols: survives a scope rename and a re-import of the rendered config" {
    "$TACCTL_BIN_SCRIPT" scope protocols prod-inner set tacacs > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope rename prod-inner core
    assert_success
    [[ "$(stored_protocols core)" == "tacacs" ]]
    # tacquito.yaml cannot carry the filter; adopting it must not lose it.
    run "$TACCTL_BIN_SCRIPT" store import --replace
    assert_success
    [[ "$(stored_protocols core)" == "tacacs" ]]
}

@test "scope protocols: rejects an unknown scope, a missing scope and an unknown subcommand" {
    run "$TACCTL_BIN_SCRIPT" scope protocols nosuch
    assert_failure
    assert_output --partial "Scope 'nosuch' does not exist"
    run "$TACCTL_BIN_SCRIPT" scope protocols nosuch set tacacs
    assert_failure
    assert_output --partial "does not exist"
    run "$TACCTL_BIN_SCRIPT" scope protocols
    assert_failure
    assert_output --partial "Usage: tacctl scope protocols"
    run "$TACCTL_BIN_SCRIPT" scope protocols lab frobnicate
    assert_failure
    assert_output --partial "Unknown subcommand"
}

@test "scope protocols: mutating it is superuser-only under the tier gate" {
    tacctl_source_lib
    run tier_permits operator scope protocols
    assert_failure
    run tier_permits readonly scope protocols
    assert_failure
    run tier_permits superuser scope protocols
    assert_success
}

@test "scope usage and completion mention the protocols verb" {
    run "$TACCTL_BIN_SCRIPT" scope
    assert_output --partial "tacctl scope protocols <scope> list|set <csv>|clear"
    grep -q 'prefixes secret protocols vendor-attrs devices aaa-order' "${TACCTL_SRC}/config/tacctl.bash-completion"
    grep -q 'scope protocols' "${TACCTL_SRC}/man/tacctl.1"
}
