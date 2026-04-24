#!/usr/bin/env bats
# Integration tests for `tacctl scope`: add, remove, rename, lookup.

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

TEST_HASH="24326224313024616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161"

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd systemctl
    stub_cmd logger

    load_fixture tacquito.minimal.yaml
}

# --- scopes add --------------------------------------------------------------

@test "scopes add: creates a new scope with prefixes + explicit secret" {
    run "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 \
        --secret "prod-secret-1234567890abcdef"
    assert_success

    # secrets[] entry appears in the YAML.
    run grep -c '^  - name: prod$' "$TACCTL_CONFIG"
    assert_output "1"
    # Prefix and secret key both land in the entry.
    run grep -F '10.0.0.0/8' "$TACCTL_CONFIG"
    assert_success
    run grep -F 'prod-secret-1234567890abcdef' "$TACCTL_CONFIG"
    assert_success
}

@test "scopes add: rejects short secret (< SECRET_MIN_LENGTH)" {
    run "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 \
        --secret "short"
    assert_failure
    assert_output --partial "minimum is"
}

@test "scopes add: rejects invalid scope name" {
    run "$TACCTL_BIN_SCRIPT" scope add "1bad" \
        --prefixes 10.0.0.0/8 \
        --secret "prod-secret-1234567890abcdef"
    assert_failure
}

@test "scopes add: rejects duplicate scope name" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    run "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 172.16.0.0/12 --secret "another-prod-1234567890abc"
    assert_failure
    assert_output --partial "already exists"
}

@test "scopes add: rejects exact-prefix collision across scopes" {
    # The collision check enforces one-scope-per-exact-prefix, not containment.
    # Tacquito resolves overlaps by first-match walk; overlapping-but-distinct
    # prefixes are legal and useful (see tacquito.multiscope.yaml fixture).
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    run "$TACCTL_BIN_SCRIPT" scope add prod-copy \
        --prefixes 10.0.0.0/8 --secret "another-secret-1234567890ab"
    assert_failure
    assert_output --partial "already claimed"
}

@test "scopes add: rejects invalid CIDR" {
    run "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes not-a-cidr --secret "prod-secret-1234567890abcdef"
    assert_failure
}

@test "scopes add: --default sets the new scope as default" {
    run "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 \
        --secret "prod-secret-1234567890abcdef" \
        --default
    assert_success
    [[ "$(conf_get scope.default)" == "prod" ]]
}

# --- scopes list / show / lookup --------------------------------------------

@test "scope list: one block per scope; prefixes rendered line-by-line" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8,10.10.0.0/16 \
        --secret "prod-secret-1234567890abcdef"
    run "$TACCTL_BIN_SCRIPT" scope list
    assert_success
    # Both scopes present, each prefix on its own line.
    assert_output --partial "lab"
    assert_output --partial "prod"
    assert_output --partial "10.10.0.0/16"
    assert_output --partial "10.0.0.0/8"
    # Each scope name appears exactly once (no per-prefix repeat).
    local prod_rows
    prod_rows=$(printf '%s\n' "$output" | sed -E 's/\x1b\[[0-9;]*m//g' | grep -cE '^  prod ')
    [[ "$prod_rows" == "1" ]]
}

@test "scope routing: one row per (scope, prefix) in first-match order" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8,10.10.0.0/16 \
        --secret "prod-secret-1234567890abcdef"
    run "$TACCTL_BIN_SCRIPT" scope routing
    assert_success
    assert_output --partial "first-match order"
    # Each prefix gets its own numbered row.
    assert_output --partial "10.0.0.0/8"
    assert_output --partial "10.10.0.0/16"
    # prod appears twice (once per prefix) in the routing view.
    local prod_rows
    prod_rows=$(printf '%s\n' "$output" | sed -E 's/\x1b\[[0-9;]*m//g' | grep -cE '^ +[0-9]+  prod ')
    [[ "$prod_rows" == "2" ]]
}

@test "scopes show: prints a scope's prefixes, secret, and user count" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    run "$TACCTL_BIN_SCRIPT" scope show prod
    assert_success
    assert_output --partial "10.0.0.0/8"
    assert_output --partial "prod-secret-1234567890abcdef"
}

@test "scope show: includes per-scope AAA order and exec-timeout" {
    # Output carries ANSI bold around the labels; --partial can't span
    # both the label and value cleanly, so strip color first.
    _show() { "$TACCTL_BIN_SCRIPT" scope show "$1" | sed -E 's/\x1b\[[0-9;]*m//g'; }

    # Defaults should display when no per-scope overrides exist.
    run _show lab
    assert_success
    assert_output --partial "AAA order:     tacacs-first"
    assert_output --partial "Exec timeout:  60 min"
    refute_output --partial "never expire"

    # After overrides, the new values appear.
    "$TACCTL_BIN_SCRIPT" scope aaa-order    lab local-first > /dev/null
    "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 15 > /dev/null
    run _show lab
    assert_success
    assert_output --partial "AAA order:     local-first"
    assert_output --partial "Exec timeout:  15 min"

    # Exec timeout 0 renders with a "never expire" annotation.
    "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 0 > /dev/null
    run _show lab
    assert_success
    assert_output --partial "Exec timeout:  0 min (never expire)"
}

@test "scopes lookup: returns owning scope for a covered IP" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    run "$TACCTL_BIN_SCRIPT" scope lookup 10.1.2.3
    assert_success
    assert_output --partial "prod"
}

# --- scopes remove -----------------------------------------------------------

@test "scopes remove: deletes an unused scope after 'y' confirmation" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove prod'
    assert_success
    run grep -c '^  - name: prod$' "$TACCTL_CONFIG"
    assert_output "0"
}

@test "scopes remove: refuses to delete a scope in use without --force" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes prod

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove prod'
    assert_failure
    assert_output --partial "still reference"
}

@test "scopes remove: --force strips scope from users and deletes" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes lab,prod

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove prod --force'
    assert_success

    # Scope is gone.
    run grep -c '^  - name: prod$' "$TACCTL_CONFIG"
    assert_output "0"

    # Alice's scope list no longer includes prod (she still has lab).
    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["lab"]'
    refute_output --partial '"prod"'
}

@test "scopes remove: refuses to delete the default scope" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef" --default

    run bash -c 'echo y | "'"$TACCTL_BIN_SCRIPT"'" scope remove prod'
    assert_failure
    assert_output --partial "default scope"
}

# --- scopes rename -----------------------------------------------------------

@test "scopes rename: renames scope and rewrites user references" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef"
    "$TACCTL_BIN_SCRIPT" user add alice superuser --hash "$TEST_HASH" --scopes prod

    run "$TACCTL_BIN_SCRIPT" scope rename prod production
    assert_success

    run grep -c '^  - name: prod$' "$TACCTL_CONFIG"
    assert_output "0"
    run grep -c '^  - name: production$' "$TACCTL_CONFIG"
    assert_output "1"

    # Alice's scope reference is rewritten.
    run grep -A4 '^  - name: alice$' "$TACCTL_CONFIG"
    assert_output --partial 'scopes: ["production"]'
}

# --- scope aaa-order (per-scope) --------------------------------------------

@test "scope aaa-order: default is tacacs-first with 'default' source" {
    run "$TACCTL_BIN_SCRIPT" scope aaa-order lab
    assert_success
    assert_output --partial "order: tacacs-first"
    assert_output --partial "Source: default"
}

@test "scope aaa-order: rejects unknown scope" {
    run "$TACCTL_BIN_SCRIPT" scope aaa-order nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

@test "scope aaa-order: set + read back per-scope override" {
    run "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first
    assert_success
    assert_output --partial "order set to local-first"
    [[ "$(conf_get aaa.order.lab)" == "local-first" ]]

    run "$TACCTL_BIN_SCRIPT" scope aaa-order lab
    assert_success
    assert_output --partial "order: local-first"
    assert_output --partial "Source: override"
}

@test "scope aaa-order: per-scope overrides are independent" {
    "$TACCTL_BIN_SCRIPT" scope add prod \
        --prefixes 10.0.0.0/8 --secret "prod-secret-1234567890abcdef" > /dev/null

    "$TACCTL_BIN_SCRIPT" scope aaa-order lab  local-first > /dev/null
    # prod not explicitly set — should still report default tacacs-first.

    [[ "$(conf_get aaa.order.lab)"  == "local-first" ]]
    [[ "$(conf_get aaa.order.prod)" == "" ]]

    run "$TACCTL_BIN_SCRIPT" scope aaa-order prod
    assert_success
    assert_output --partial "order: tacacs-first"
    assert_output --partial "Source: default"
}

@test "scope aaa-order: local-first set on a scope warns about collisions" {
    # Setting local-first (the non-default posture) should surface the
    # collision caveat so operators understand the risk.
    run "$TACCTL_BIN_SCRIPT" scope aaa-order lab local-first
    assert_success
    assert_output --partial "collide with TACACS+"
}

@test "scope aaa-order: rejects invalid enum value" {
    run "$TACCTL_BIN_SCRIPT" scope aaa-order lab sideways
    assert_failure
    assert_output --partial "must be one of: tacacs-first, local-first"
}

# --- scope exec-timeout (per-scope) -----------------------------------------

@test "scope exec-timeout: default is 60 with 'default' source" {
    run "$TACCTL_BIN_SCRIPT" scope exec-timeout lab
    assert_success
    assert_output --partial "exec-timeout: 60 minute"
    assert_output --partial "Source: default"
}

@test "scope exec-timeout: rejects unknown scope" {
    run "$TACCTL_BIN_SCRIPT" scope exec-timeout nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

@test "scope exec-timeout: set + read back per-scope override" {
    run "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 15
    assert_success
    assert_output --partial "exec-timeout set to 15"
    [[ "$(conf_get exec_timeout.lab)" == "15" ]]

    run "$TACCTL_BIN_SCRIPT" scope exec-timeout lab
    assert_success
    assert_output --partial "exec-timeout: 15 minute"
    assert_output --partial "Source: override"
}

@test "scope exec-timeout: value 0 warns about disabling expiry" {
    run "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 0
    assert_success
    assert_output --partial "disables idle-session expiry"
    assert_output --partial "security risk"
}

@test "scope exec-timeout: rejects out-of-range + non-numeric" {
    run "$TACCTL_BIN_SCRIPT" scope exec-timeout lab 90
    assert_failure
    assert_output --partial "must be <= 60"

    run "$TACCTL_BIN_SCRIPT" scope exec-timeout lab forever
    assert_failure
    assert_output --partial "must be an integer"
}

# --- scope tacacs-group (per-scope) -----------------------------------------

@test "scope tacacs-group: default is TACACS-GROUP with 'default' source" {
    run "$TACCTL_BIN_SCRIPT" scope tacacs-group lab
    assert_success
    assert_output --partial "aaa-group-server name: TACACS-GROUP"
    assert_output --partial "Source: default"
}

@test "scope tacacs-group: rejects unknown scope" {
    run "$TACCTL_BIN_SCRIPT" scope tacacs-group nosuchscope
    assert_failure
    assert_output --partial "does not exist"
}

@test "scope tacacs-group: set + read back per-scope override" {
    run "$TACCTL_BIN_SCRIPT" scope tacacs-group lab TACACS_PROD
    assert_success
    assert_output --partial "aaa-group-server label set to TACACS_PROD"
    [[ "$(conf_get tacacs_group.lab)" == "TACACS_PROD" ]]

    run "$TACCTL_BIN_SCRIPT" scope tacacs-group lab
    assert_success
    assert_output --partial "name: TACACS_PROD"
    assert_output --partial "Source: override"
}

@test "scope tacacs-group: rejects invalid names" {
    run "$TACCTL_BIN_SCRIPT" scope tacacs-group lab "has spaces"
    assert_failure
    run "$TACCTL_BIN_SCRIPT" scope tacacs-group lab "9-digit-start"
    assert_failure
    assert_output --partial "must start with a letter"
}

# --- scope mgmt-acl (per-scope) ---------------------------------------------

@test "scope mgmt-acl: default shows shipped default with 'default' source" {
    run "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab cisco-name
    assert_success
    assert_output --partial "cisco mgmt-ACL name: VTY-ACL"
    assert_output --partial "Source: default"

    run "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab juniper-name
    assert_success
    assert_output --partial "juniper mgmt-ACL name: MGMT-ACL"
    assert_output --partial "Source: default"
}

@test "scope mgmt-acl: respects the global override when per-scope unset" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl cisco-name   SITE-VTY   > /dev/null
    "$TACCTL_BIN_SCRIPT" config mgmt-acl juniper-name SITE-MGMT  > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab cisco-name
    assert_success
    assert_output --partial "cisco mgmt-ACL name: SITE-VTY"
    assert_output --partial "Source: global"
}

@test "scope mgmt-acl: per-scope override wins over global" {
    "$TACCTL_BIN_SCRIPT" config mgmt-acl cisco-name SITE-VTY > /dev/null
    "$TACCTL_BIN_SCRIPT" scope  mgmt-acl lab cisco-name LAB-VTY > /dev/null
    run "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab cisco-name
    assert_success
    assert_output --partial "cisco mgmt-ACL name: LAB-VTY"
    assert_output --partial "Source: override"
    [[ "$(conf_get mgmt_acl.names.cisco.lab)" == "LAB-VTY" ]]
}

@test "scope mgmt-acl: rejects unknown scope / subcommand / name" {
    run "$TACCTL_BIN_SCRIPT" scope mgmt-acl nosuchscope cisco-name
    assert_failure
    assert_output --partial "does not exist"

    run "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab ios-name
    assert_failure
    assert_output --partial "cisco-name | juniper-name"

    run "$TACCTL_BIN_SCRIPT" scope mgmt-acl lab cisco-name "1bad"
    assert_failure
    assert_output --partial "must start with a letter"
}
