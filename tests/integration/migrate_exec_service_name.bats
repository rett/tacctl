#!/usr/bin/env bats
# Integration tests for conf_migrate_exec_service_name(): the one-shot that
# heals pre-a1e39e6 installs whose Cisco exec services use the legacy
# `name: exec` (devices request `service=shell`, so authorization failed
# post-auth and clients reported "invalid password").

load ../helpers/setup
load ../helpers/tmpenv
load ../helpers/mocks
load ../helpers/fixtures

setup() {
    tacctl_tmpenv_init
    tacctl_mocks_init
    stub_cmd chown
    stub_cmd logger
    load_fixture tacquito.legacy-exec.yaml
    tacctl_source_lib
}

backup_count() {
    ls -1 "${TACCTL_ETC}/backups"/tacquito.yaml.* 2>/dev/null | wc -l
}

@test "migrate exec->shell: rewrites all three Cisco exec service anchors" {
    run conf_migrate_exec_service_name
    assert_success
    assert_output --partial "exec → shell for 3 group(s)"

    # All three exec anchors now say `name: shell`; no legacy `name: exec` left.
    run grep -c '^  name: shell$' "$TACCTL_CONFIG"
    assert_output "3"
    run grep -c '^  name: exec$' "$TACCTL_CONFIG"
    assert_output "0"
}

@test "migrate exec->shell: leaves junos-exec services untouched" {
    conf_migrate_exec_service_name
    run grep -c '^  name: junos-exec$' "$TACCTL_CONFIG"
    assert_output "3"
}

@test "migrate exec->shell: preserves each anchor's priv-lvl values" {
    conf_migrate_exec_service_name
    run grep -A4 '^exec_operator:' "$TACCTL_CONFIG"
    assert_output --partial "name: shell"
    assert_output --partial "values: [7]"
    run grep -A4 '^exec_superuser:' "$TACCTL_CONFIG"
    assert_output --partial "values: [15]"
}

@test "migrate exec->shell: snapshots the pre-migration config" {
    [ "$(backup_count)" -eq 0 ]
    conf_migrate_exec_service_name
    [ "$(backup_count)" -eq 1 ]
    # The snapshot is the legacy (pre-migration) content.
    local snap
    snap=$(ls "${TACCTL_ETC}/backups"/tacquito.yaml.*)
    run grep -c '^  name: exec$' "$snap"
    assert_output "3"
}

@test "migrate exec->shell: second run is an idempotent no-op" {
    conf_migrate_exec_service_name
    local before_sum before_backups
    before_sum=$(cksum "$TACCTL_CONFIG")
    before_backups=$(backup_count)

    run conf_migrate_exec_service_name
    assert_success
    refute_output --partial "Migrated"

    # No new backup, byte-identical config.
    [ "$(backup_count)" -eq "$before_backups" ]
    [ "$(cksum "$TACCTL_CONFIG")" = "$before_sum" ]
}

@test "migrate exec->shell: no-op on an already-current (name: shell) config" {
    load_fixture tacquito.minimal.yaml
    run conf_migrate_exec_service_name
    assert_success
    refute_output --partial "Migrated"
    [ "$(backup_count)" -eq 0 ]
}
