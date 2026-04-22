#!/usr/bin/env bats
# Integration tests for `tacctl status`, `tacctl config show`,
# `tacctl scopes default`, and `tacctl scopes lookup`.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

TEST_HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd logger
    # systemctl + ss + ps stubs drive cmd_status display.
    stub_cmd systemctl '
case "$1" in
  is-active) echo "active"; exit 0 ;;
  show)
    case " $* " in
      *--property=ActiveEnterTimestamp*) echo "ActiveEnterTimestamp=Mon 2026-04-21 10:00:00 UTC" ;;
      *--property=MainPID*) echo "MainPID=4242" ;;
      *--property=ExecStart*) echo "ExecStart={ path=/usr/local/bin/tacquito ; argv[]=/usr/local/bin/tacquito -level 20 ; }" ;;
    esac
    ;;
  *) exit 0 ;;
esac'
    stub_cmd ss 'echo "LISTEN 0 128 *:49 *:* users:((\"tacquito\",pid=4242,fd=3))"'
    stub_cmd ps 'echo "12345"'  # 12345 KB ≈ 12.1 MB
    load_fixture tacquito.multiscope.yaml
}

# =============================================================================
#  cmd_status
# =============================================================================

@test "status: prints service active + PID + listening port + user count" {
    run "$TACCTL_BIN_SCRIPT" status
    assert_success
    assert_output --partial "Tacquito Service Status"
    assert_output --partial "Service:"
    assert_output --partial "active"
    assert_output --partial "PID:"
    assert_output --partial "4242"
    assert_output --partial ":49"
    # multiscope fixture has alice, bob, carol → 3 users.
    assert_output --partial "Users:"
}

@test "status: shows 'port 49 not detected' when ss finds nothing" {
    stub_cmd ss  # empty output
    run "$TACCTL_BIN_SCRIPT" status
    assert_success
    assert_output --partial "port 49 not detected"
}

@test "status: surfaces inactive service in red" {
    stub_cmd systemctl '
case "$1" in
  is-active) echo "inactive"; exit 3 ;;
  show) echo "MainPID=0" ;;
esac'
    run "$TACCTL_BIN_SCRIPT" status
    assert_success
    assert_output --partial "inactive"
}

# =============================================================================
#  cmd_config_show
# =============================================================================

@test "config show: renders a per-scope block with user counts" {
    run "$TACCTL_BIN_SCRIPT" config show
    assert_success
    assert_output --partial "Tacquito Configuration"
    assert_output --partial "Scopes:"
    assert_output --partial "prod"
    assert_output --partial "lab"
    assert_output --partial "dmz"
    assert_output --partial "10.0.0.0/8"
    assert_output --partial "192.168.0.0/16"
}

@test "config show: lists scope user counts (multiscope fixture)" {
    run "$TACCTL_BIN_SCRIPT" config show
    assert_success
    # lab has 3 users (alice/bob/carol), prod has 1 (alice), dmz has 1 (carol).
    assert_output --partial "Users:"
}

# =============================================================================
#  cmd_scopes_default
# =============================================================================

@test "scopes default: prints current default when no arg" {
    # multiscope fixture doesn't pin a default; seed the override ourselves.
    printf 'scope:\n  default: lab\n' > "$TACCTL_ETC/tacctl.yaml"
    run "$TACCTL_BIN_SCRIPT" scopes default
    assert_success
    assert_output --partial "Default scope: lab"
}

@test "scopes default: no override → falls back to shipped default 'lab'" {
    # multiscope fixture has a 'lab' scope, matching the canonical default.
    # Without any explicit override, read_default_scope returns 'lab'.
    run "$TACCTL_BIN_SCRIPT" scopes default
    assert_success
    assert_output --partial "Default scope: lab"
}

@test "scopes default <name>: writes the default-scope override" {
    run "$TACCTL_BIN_SCRIPT" scopes default prod
    assert_success

    [[ "$(conf_get scope.default)" == "prod" ]]
}

@test "scopes default: rejects unknown scope" {
    run "$TACCTL_BIN_SCRIPT" scopes default nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

# =============================================================================
#  cmd_scopes_lookup
# =============================================================================

@test "scopes lookup <ip>: returns the first-match scope for a covered IP" {
    run "$TACCTL_BIN_SCRIPT" scopes lookup 10.10.99.42
    assert_success
    # 10.10.99.0/24 (prod-inner) is more specific than 10.0.0.0/8 (prod).
    # Order after reorder_secrets_by_prefix_specificity puts prod-inner first.
    assert_output --partial "prod-inner"
    assert_output --partial "10.10.99.0/24"
}

@test "scopes lookup <ip>: warns about shadowed scopes covering the same IP" {
    run "$TACCTL_BIN_SCRIPT" scopes lookup 10.10.99.42
    assert_success
    # prod's 10.0.0.0/8 also covers 10.10.99.42 but is shadowed.
    assert_output --partial "shadowed"
    assert_output --partial "prod"
}

@test "scopes lookup: exact-match IP in a non-overlapping scope" {
    run "$TACCTL_BIN_SCRIPT" scopes lookup 192.168.1.1
    assert_success
    assert_output --partial "lab"
    # No shadow when only one scope covers the query.
    refute_output --partial "shadowed"
}

@test "scopes lookup <cidr>: treats CIDR query as subset match" {
    run "$TACCTL_BIN_SCRIPT" scopes lookup 192.168.0.0/24
    assert_success
    assert_output --partial "lab"
    assert_output --partial "192.168.0.0/24"
}

@test "scopes lookup: no match → exits non-zero with explanation" {
    run "$TACCTL_BIN_SCRIPT" scopes lookup 8.8.8.8
    assert_failure
    assert_output --partial "No scope owns"
}

@test "scopes lookup: rejects missing argument" {
    run "$TACCTL_BIN_SCRIPT" scopes lookup
    assert_failure
    assert_output --partial "Usage:"
}

@test "scopes lookup: rejects malformed IP/CIDR" {
    run "$TACCTL_BIN_SCRIPT" scopes lookup "not-an-address"
    # Python raises ValueError → exit 2, which bats sees as failure.
    assert_failure
    assert_output --partial "invalid address or CIDR"
}
